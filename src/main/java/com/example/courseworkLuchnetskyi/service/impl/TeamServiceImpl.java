package com.example.courseworkLuchnetskyi.service.impl;

import com.example.courseworkLuchnetskyi.dto.TeamMatchDto;
import com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.exception.EntityNotFoundException;
import com.example.courseworkLuchnetskyi.mapper.TeamMapper;
import com.example.courseworkLuchnetskyi.model.Match;
import com.example.courseworkLuchnetskyi.model.Team;
import com.example.courseworkLuchnetskyi.repository.MatchRepository;
import com.example.courseworkLuchnetskyi.repository.TeamRepository;
import com.example.courseworkLuchnetskyi.service.TeamService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TeamServiceImpl implements TeamService {

    private final TeamRepository teamRepository;
    private final TeamMapper teamMapper;
    private final MatchRepository matchRepository; 

    @Override
    public TeamResponseDto createTeam(TeamRequestDto requestDto) {
        Team team = teamMapper.toEntity(requestDto);
        return teamMapper.toDto(teamRepository.save(team));
    }

    @Override
    public List<TeamResponseDto> getAllTeams() {
        return teamRepository.findAll()
                .stream()
                .map(teamMapper::toDto)
                .toList();
    }

    @Override
    public TeamResponseDto updateTeam(Long id, TeamRequestDto requestDto) {
        Team team = teamRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Team not found with id: " + id));
        teamMapper.updateTeamFromDto(team, requestDto);
        return teamMapper.toDto(teamRepository.save(team));
    }

    @Override
    public void deleteTeam(Long id) {
        if (!teamRepository.existsById(id)) {
            throw new EntityNotFoundException("Team not found with id: " + id);
        }
        teamRepository.deleteById(id);
    }

    @Override
    public List<TeamMatchDto> getMatchesForTeam(Long teamId) {
        teamRepository.findById(teamId)
            .orElseThrow(() -> new RuntimeException("Team not found with id: " + teamId));

        List<Match> matches = matchRepository.findByTeamAIdOrTeamBId(teamId, teamId);

        return matches.stream().map(match -> {
            TeamMatchDto dto = new TeamMatchDto();
            dto.setMatchId(match.getId());
            dto.setDate(match.getDate());
            dto.setTournamentName(match.getTournament().getName());

            if (match.getTeamA().getId().equals(teamId)) {
                dto.setOpponent(match.getTeamB().getName());
                dto.setScoreFor(match.getScoreA());
                dto.setScoreAgainst(match.getScoreB());
            } else {
                dto.setOpponent(match.getTeamA().getName());
                dto.setScoreFor(match.getScoreB());
                dto.setScoreAgainst(match.getScoreA());
            }

            return dto;
        }).toList();
    }
}
