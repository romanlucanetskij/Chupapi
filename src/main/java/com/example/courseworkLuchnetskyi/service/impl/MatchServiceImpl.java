package com.example.courseworkLuchnetskyi.service.impl;

import com.example.courseworkLuchnetskyi.dto.MatchScheduleDto;
import com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto;
import com.example.courseworkLuchnetskyi.mapper.MatchMapper;
import com.example.courseworkLuchnetskyi.model.Match;
import com.example.courseworkLuchnetskyi.repository.MatchRepository;
import com.example.courseworkLuchnetskyi.repository.TeamRepository;
import com.example.courseworkLuchnetskyi.repository.TournamentRepository;
import com.example.courseworkLuchnetskyi.service.MatchService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MatchServiceImpl implements MatchService {

    private final MatchRepository matchRepository;
    private final TournamentRepository tournamentRepository;
    private final TeamRepository teamRepository;
    private final MatchMapper matchMapper;

    @Override
    public MatchResponseDto createMatch(MatchRequestDto dto) {
        Match match = matchMapper.toEntity(dto);

        match.setTournament(tournamentRepository.findById(dto.tournamentId())
                .orElseThrow(() -> new RuntimeException("Tournament not found")));

        match.setTeamA(teamRepository.findById(dto.teamAId())
                .orElseThrow(() -> new RuntimeException("Team A not found")));

        match.setTeamB(teamRepository.findById(dto.teamBId())
                .orElseThrow(() -> new RuntimeException("Team B not found")));

        return matchMapper.toDto(matchRepository.save(match));
    }

    @Override
    public List<MatchResponseDto> getMatchesByTournament(Long tournamentId) {
        return matchRepository.findByTournamentId(tournamentId).stream()
                .map(matchMapper::toDto)
                .toList();
    }

    @Override
    public MatchResponseDto updateMatch(Long id, MatchRequestDto dto) {
        Match match = matchRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Match not found"));

        matchMapper.updateFromDto(match, dto);

        if (dto.tournamentId() != null) {
            match.setTournament(tournamentRepository.findById(dto.tournamentId())
                    .orElseThrow(() -> new RuntimeException("Tournament not found")));
        }
        if (dto.teamAId() != null) {
            match.setTeamA(teamRepository.findById(dto.teamAId())
                    .orElseThrow(() -> new RuntimeException("Team A not found")));
        }
        if (dto.teamBId() != null) {
            match.setTeamB(teamRepository.findById(dto.teamBId())
                    .orElseThrow(() -> new RuntimeException("Team B not found")));
        }

        return matchMapper.toDto(matchRepository.save(match));
    }

    @Override
    public void deleteMatch(Long id) {
        matchRepository.deleteById(id);
    }

    @Override
    public List<MatchScheduleDto> getTournamentSchedule(Long tournamentId) {
        return matchRepository.findByTournamentId(tournamentId).stream()
                .map(match -> {
                    MatchScheduleDto dto = new MatchScheduleDto();
                    dto.setMatchId(match.getId());
                    dto.setTeamA(match.getTeamA().getName());
                    dto.setTeamB(match.getTeamB().getName());
                    dto.setDate(match.getDate());
                    return dto;
                })
                .toList();
    }
}
