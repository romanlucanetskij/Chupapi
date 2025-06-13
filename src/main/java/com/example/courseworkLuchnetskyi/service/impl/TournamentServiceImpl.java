package com.example.courseworkLuchnetskyi.service.impl;

import com.example.courseworkLuchnetskyi.dto.TournamentStandingDto;
import com.example.courseworkLuchnetskyi.dto.request.TournamentRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.model.Match;
import com.example.courseworkLuchnetskyi.model.Participation;
import com.example.courseworkLuchnetskyi.model.Tournament;
import com.example.courseworkLuchnetskyi.repository.MatchRepository;
import com.example.courseworkLuchnetskyi.repository.ParticipationRepository;
import com.example.courseworkLuchnetskyi.repository.TournamentRepository;
import com.example.courseworkLuchnetskyi.service.TournamentService;
import com.example.courseworkLuchnetskyi.mapper.TournamentMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import jakarta.persistence.EntityNotFoundException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TournamentServiceImpl implements TournamentService {

    private final TournamentRepository tournamentRepository;
    private final TournamentMapper tournamentMapper;
    private final MatchRepository matchRepository;
    private final ParticipationRepository participationRepository;

    @Override
    public TournamentResponseDto createTournament(TournamentRequestDto request) {
        Tournament tournament = tournamentMapper.toEntity(request);
        return tournamentMapper.toDto(tournamentRepository.save(tournament));
    }

    @Override
    public List<TournamentResponseDto> getAllTournaments() {
        return tournamentRepository.findAll().stream()
                .map(tournamentMapper::toDto)
                .toList();
    }

    @Override
    public TournamentResponseDto updateTournament(Long id, TournamentRequestDto request) {
        Tournament tournament = tournamentRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tournament not found"));
        tournamentMapper.updateTournamentFromRequest(tournament, request);
        return tournamentMapper.toDto(tournamentRepository.save(tournament));
    }

    @Override
    public void deleteTournament(Long id) {
        tournamentRepository.deleteById(id);
    }

    @Override
    public List<TournamentStandingDto> getTournamentStandings(Long tournamentId) {
        List<Participation> participations = participationRepository.findByTournamentId(tournamentId);
        List<Match> matches = matchRepository.findByTournamentId(tournamentId);

        Map<Long, TournamentStandingDto> standings = new HashMap<>();

        for (Participation p : participations) {
            TournamentStandingDto dto = new TournamentStandingDto();
            dto.setTeamName(p.getTeam().getName());
            standings.put(p.getTeam().getId(), dto);
        }

        for (Match match : matches) {
            Long teamAId = match.getTeamA().getId();
            Long teamBId = match.getTeamB().getId();
            int scoreA = match.getScoreA();
            int scoreB = match.getScoreB();

            TournamentStandingDto teamAStats = standings.get(teamAId);
            TournamentStandingDto teamBStats = standings.get(teamBId);

            teamAStats.setMatchesPlayed(teamAStats.getMatchesPlayed() + 1);
            teamBStats.setMatchesPlayed(teamBStats.getMatchesPlayed() + 1);

            teamAStats.setGoalsFor(teamAStats.getGoalsFor() + scoreA);
            teamAStats.setGoalsAgainst(teamAStats.getGoalsAgainst() + scoreB);

            teamBStats.setGoalsFor(teamBStats.getGoalsFor() + scoreB);
            teamBStats.setGoalsAgainst(teamBStats.getGoalsAgainst() + scoreA);

            if (scoreA > scoreB) {
                teamAStats.setWins(teamAStats.getWins() + 1);
                teamBStats.setLosses(teamBStats.getLosses() + 1);
                teamAStats.setPoints(teamAStats.getPoints() + 3);
            } else if (scoreA < scoreB) {
                teamBStats.setWins(teamBStats.getWins() + 1);
                teamAStats.setLosses(teamAStats.getLosses() + 1);
                teamBStats.setPoints(teamBStats.getPoints() + 3);
            } else {
                teamAStats.setDraws(teamAStats.getDraws() + 1);
                teamBStats.setDraws(teamBStats.getDraws() + 1);
                teamAStats.setPoints(teamAStats.getPoints() + 1);
                teamBStats.setPoints(teamBStats.getPoints() + 1);
            }
        }

        standings.values().forEach(dto ->
                dto.setGoalDifference(dto.getGoalsFor() - dto.getGoalsAgainst()));

        return new ArrayList<>(standings.values()).stream()
                .sorted(Comparator.comparingInt(TournamentStandingDto::getPoints).reversed()
                        .thenComparingInt(TournamentStandingDto::getGoalDifference).reversed()
                        .thenComparingInt(TournamentStandingDto::getGoalsFor).reversed())
                .toList();
    }

    @Override
    public List<com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto> getTournamentWinners() {
        List<Tournament> tournaments = tournamentRepository.findAll();
        List<com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto> winners = new ArrayList<>();

        for (Tournament tournament : tournaments) {
            List<Match> matches = matchRepository.findByTournamentId(tournament.getId());

            Map<com.example.courseworkLuchnetskyi.model.Team, Integer> winCount = new HashMap<>();

            for (Match match : matches) {
                com.example.courseworkLuchnetskyi.model.Team winner = determineMatchWinner(match);
                if (winner != null) {
                    winCount.put(winner, winCount.getOrDefault(winner, 0) + 1);
                }
            }

            com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto winnerDto = new com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto();
            winnerDto.setTournamentName(tournament.getName());

            winCount.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .ifPresent(entry -> winnerDto.setWinningTeamName(entry.getKey().getName()));

            winners.add(winnerDto);
        }
        return winners;
    }

    private com.example.courseworkLuchnetskyi.model.Team determineMatchWinner(com.example.courseworkLuchnetskyi.model.Match match) {
        if (match.getScoreA() > match.getScoreB()) {
            return match.getTeamA();
        } else if (match.getScoreB() > match.getScoreA()) {
            return match.getTeamB();
        } else {
            return null; // Draw
        }
    }
}
