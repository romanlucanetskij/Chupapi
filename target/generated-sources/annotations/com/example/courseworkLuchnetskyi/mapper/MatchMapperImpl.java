package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.model.Match;
import com.example.courseworkLuchnetskyi.model.Team;
import com.example.courseworkLuchnetskyi.model.Tournament;
import java.time.LocalDate;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2025-06-12T13:09:29+0300",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 17.0.13 (Amazon.com Inc.)"
)
@Component
public class MatchMapperImpl implements MatchMapper {

    @Override
    public Match toEntity(MatchRequestDto dto) {
        if ( dto == null ) {
            return null;
        }

        Match match = new Match();

        match.setDate( dto.date() );
        match.setScoreA( dto.scoreA() );
        match.setScoreB( dto.scoreB() );

        return match;
    }

    @Override
    public MatchResponseDto toDto(Match match) {
        if ( match == null ) {
            return null;
        }

        Long id = null;
        TournamentResponseDto tournament = null;
        TeamResponseDto teamA = null;
        TeamResponseDto teamB = null;
        LocalDate date = null;
        Integer scoreA = null;
        Integer scoreB = null;

        id = match.getId();
        tournament = tournamentToTournamentResponseDto( match.getTournament() );
        teamA = teamToTeamResponseDto( match.getTeamA() );
        teamB = teamToTeamResponseDto( match.getTeamB() );
        date = match.getDate();
        scoreA = match.getScoreA();
        scoreB = match.getScoreB();

        MatchResponseDto matchResponseDto = new MatchResponseDto( id, tournament, teamA, teamB, date, scoreA, scoreB );

        return matchResponseDto;
    }

    @Override
    public void updateFromDto(Match match, MatchRequestDto dto) {
        if ( dto == null ) {
            return;
        }

        if ( dto.date() != null ) {
            match.setDate( dto.date() );
        }
        if ( dto.scoreA() != null ) {
            match.setScoreA( dto.scoreA() );
        }
        if ( dto.scoreB() != null ) {
            match.setScoreB( dto.scoreB() );
        }
    }

    protected TournamentResponseDto tournamentToTournamentResponseDto(Tournament tournament) {
        if ( tournament == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        LocalDate startDate = null;
        LocalDate endDate = null;
        String location = null;

        id = tournament.getId();
        name = tournament.getName();
        startDate = tournament.getStartDate();
        endDate = tournament.getEndDate();
        location = tournament.getLocation();

        TournamentResponseDto tournamentResponseDto = new TournamentResponseDto( id, name, startDate, endDate, location );

        return tournamentResponseDto;
    }

    protected TeamResponseDto teamToTeamResponseDto(Team team) {
        if ( team == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        String city = null;

        id = team.getId();
        name = team.getName();
        city = team.getCity();

        TeamResponseDto teamResponseDto = new TeamResponseDto( id, name, city );

        return teamResponseDto;
    }
}
